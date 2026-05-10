#!/usr/bin/env python3

import pickle
import numpy as np
import pandas as pd
import re
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------- 1. Load supervised model (XGBoost) ----------
with open('xgboost_model.pkl', 'rb') as f:
    sup_data = pickle.load(f)
with open('preprocessors.pkl', 'rb') as f: 
    sup_prep = pickle.load(f)

sup_model = sup_data['model']
sup_features = sup_data['features']          # 12 names

# ---------- 2. Load unsupervised model (Isolation Forest) ----------
with open('isolation_forest_model.pkl', 'rb') as f:
    unsup_data = pickle.load(f)
with open('preprocessors_1.pkl', 'rb') as f: 
    unsup_prep = pickle.load(f)

unsup_model = unsup_data['model']
unsup_threshold = unsup_data['threshold']
unsup_features = unsup_data['features']      # 6 names: user_enc, cmd_enc, pri_enc, register_num, value, register_known

# ---------- Shared preprocessors (both models use the same encodings) ----------
le_user = sup_prep['le_user']
le_cmd  = sup_prep['le_cmd']
le_pri  = sup_prep['le_pri']
le_func = sup_prep['le_func']
le_dev  = sup_prep['le_dev']
scaler_sup = sup_prep['scaler']

# Unsupervised scaler and encoders (might be different, but we use sup's for consistency)
# To be safe, use unsup's encoders for its own 6 features
le_user_unsup = unsup_prep['le_user']
le_cmd_unsup  = unsup_prep['le_cmd']
le_pri_unsup  = unsup_prep['le_pri']
scaler_unsup  = unsup_prep['scaler']

VALID_REGISTERS = sup_prep['valid_registers']
VALID_DEVICES   = sup_prep['valid_devices']
SUSPICIOUS_KW   = sup_prep['suspicious_keywords']

# ---------- Helper ----------
def extract_reg_num(reg):
    if isinstance(reg, str):
        m = re.search(r'\d+', reg)
        return float(m.group()) if m else -1.0
    return float(reg) if pd.notna(reg) else -1.0

# ---------- Scoring endpoint ----------
@app.route('/score', methods=['POST'])
def score_command():
    try:
        data = request.json

        # --- Extract request fields ---
        user = data.get('user', data.get('issued_by', 'Admin1'))
        cmd_type = data.get('command_type', 'read').lower()
        if cmd_type in ['r', 'read']:
            cmd_type = 'read'
        elif cmd_type in ['w', 'write']:
            cmd_type = 'write'

        priority = data.get('priority', 'normal')
        register = data.get('register', data.get('register_number', 'HR_40001'))
        value = float(data.get('value', 0) or 0)
        func_code = int(data.get('function_code', 0) or 0)
        device_id = data.get('device_id', 'PLC-001')
        description = str(data.get('description', ''))
        timestamp_str = data.get('timestamp', None)

        # --- Derived features ---
        reg_num = extract_reg_num(register)
        reg_known = 1 if reg_num in VALID_REGISTERS else 0
        dev_known = 1 if str(device_id).upper() in VALID_DEVICES else 0
        desc_len = len(description.strip())
        desc_susp = 1 if any(w in description.lower() for w in SUSPICIOUS_KW) else 0

        if timestamp_str:
            try:
                ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)
        hour = ts.hour
        day = ts.weekday()

        if func_code == 0:
            func_code = 3 if cmd_type == 'read' else 6

        # --- Encode categoricals (graceful fallback) ---
        def encode(le, val, name):
            try:
                return le.transform([val])[0]
            except ValueError:
                raise ValueError(f'Unknown {name}: {val}')

        try:
            user_enc_sup = encode(le_user, user, 'user')
            user_enc_unsup = encode(le_user_unsup, user, 'user')
        except ValueError as e:
            return jsonify({'unsup_anomaly_score': 1.0, 'unsup_is_anomaly': 1,
                            'sup_is_anomaly': 1, 'sup_attack_probability': 1.0,
                            'status': 'success', 'reason': str(e)})
        try:
            cmd_enc_sup = encode(le_cmd, cmd_type, 'command_type')
            cmd_enc_unsup = encode(le_cmd_unsup, cmd_type, 'command_type')
        except ValueError as e:
            return jsonify({'unsup_anomaly_score': 1.0, 'unsup_is_anomaly': 1,
                            'sup_is_anomaly': 1, 'sup_attack_probability': 1.0,
                            'status': 'success', 'reason': str(e)})
        try:
            pri_enc_sup = encode(le_pri, priority, 'priority')
            pri_enc_unsup = encode(le_pri_unsup, priority, 'priority')
        except ValueError as e:
            return jsonify({'unsup_anomaly_score': 1.0, 'unsup_is_anomaly': 1,
                            'sup_is_anomaly': 1, 'sup_attack_probability': 1.0,
                            'status': 'success', 'reason': str(e)})

        try:
            func_enc = le_func.transform([func_code])[0]
        except ValueError:
            return jsonify({'unsup_anomaly_score': 1.0, 'unsup_is_anomaly': 1,
                            'sup_is_anomaly': 1, 'sup_attack_probability': 1.0,
                            'status': 'success', 'reason': f'Unknown function code: {func_code}'})
        try:
            dev_enc = le_dev.transform([str(device_id)])[0]
        except ValueError:
            return jsonify({'unsup_anomaly_score': 1.0, 'unsup_is_anomaly': 1,
                            'sup_is_anomaly': 1, 'sup_attack_probability': 1.0,
                            'status': 'success', 'reason': f'Unknown device: {device_id}'})

        # --- Unsupervised prediction (6 features) ---
        X_unsup = pd.DataFrame([[user_enc_unsup, cmd_enc_unsup, pri_enc_unsup,
                                 reg_num, value, reg_known]],
                               columns=unsup_features)
        X_unsup_scaled = scaler_unsup.transform(X_unsup)
        unsup_raw = unsup_model.score_samples(X_unsup_scaled)[0]
        unsup_score = -unsup_raw
        unsup_flag = 1 if unsup_score > unsup_threshold else 0

        # --- Supervised prediction (12 features) ---
        X_sup = pd.DataFrame([[user_enc_sup, cmd_enc_sup, pri_enc_sup,
                               reg_num, value, reg_known,
                               func_enc, dev_enc, desc_len, desc_susp,
                               hour, day]],
                             columns=sup_features)
        X_sup_scaled = scaler_sup.transform(X_sup)
        sup_proba = sup_model.predict_proba(X_sup_scaled)[0][1]
        sup_flag = 1 if sup_proba >= 0.5 else 0

        return jsonify({
            'unsup_anomaly_score': round(float(unsup_score), 4),
            'unsup_is_anomaly': unsup_flag,
            'sup_is_anomaly': sup_flag,
            'sup_attack_probability': round(float(sup_proba), 4),
            'status': 'success'
        })

    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
