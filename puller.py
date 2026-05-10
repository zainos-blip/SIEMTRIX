#!/usr/bin/env python3

from fastapi import FastAPI
import pika, json, threading
from zeep import Client
from zeep.helpers import serialize_object
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

RABBIT_HOST = os.getenv("RABBIT_HOST")
RABBIT_USER = os.getenv("RABBIT_USER")
RABBIT_PASS = os.getenv("RABBIT_PASS")

COMMANDS_QUEUE = os.getenv("RABBIT_QUEUE")
RABBIT_RESULT_QUEUE = os.getenv("RABBIT_RESULT_QUEUE")
RABBIT_MAX_PRIORITY = int(os.getenv("RABBIT_MAX_PRIORITY"))

SCADABR_WSDL = os.getenv("SCADABR_WSDL")

soap_client = Client(SCADABR_WSDL)
app = FastAPI(title="OT Puller Service")


# SCADABR SOAP FUNCTIONS (WRITE AND READ FUNCTIONS)
# Map your HR_40001 etc to actual ScadaBR point names
TAG_MAPPING = {
    "HR_40001": "Point 1",
    "HR_40002": "Point 2",  
    "HR_40003": "Point 3",
    "HR_40004": "Point 4",
    "HR_40005": "Point 5",
    "HR_40006": "Point 6",
    "HR_40007": "Point 7",
    "HR_40008": "Point 8",
    "HR_40009": "Point 9",
    "HR_40010": "Point 10",
    "HR_40011": "Point 11",
    # mappings till HR_40011 
}


#sending both response and command logs to the command validation index
def send_to_splunk(log_data: dict, sourcetype: str):
    url = os.getenv("SPLUNK_HEC_URL")
    token = os.getenv("SPLUNK_HEC_TOKEN")

    if not url or not token:
        return False, "Splunk HEC config missing"
    
    headers = {"Authorization": f"Splunk {token}",
               "Content-Type": "application/json"}
    payload = {
        "host": "ot_puller",
        "source": "ot_puller_service",
        "index": "ot_execution",
        "event": log_data,
    }

    import requests
    try:
        r = requests.post(url, headers=headers, data=json.dumps(payload), verify=False, timeout=7)
        if r.status_code in (200, 201):
            return True, None
        return False, r.text
    
    except Exception as e:
        return False, str(e)
    
    

        
def scadabr_write(tag_path: str, value):
    try:
        print(f"🔄 Attempting to write to ScadaBR - XID: {tag_path}, Value: {value}")
        
        actual_tag = TAG_MAPPING.get(tag_path, tag_path)
        print(f"📋 Mapped {tag_path} -> {actual_tag}")
        
        # Method 1: Try writeStringData with proper options
        try:
            # Create proper options parameter - IMPORTANT: Set returnItemValues to TRUE
            options = {
                "returnItemValues": True  # CHANGED TO TRUE
            }
            
            # Create proper item structure
            items_list = [{
                "itemName": actual_tag,
                "value": str(value)  # Convert to string for writeStringData
            }]
            
            print(f"🔍 Calling writeStringData with: itemsList={items_list}, options={options}")
            
            response = soap_client.service.writeStringData(
                itemsList=items_list,
                options=options
            )
            
            # DEBUG: Print the raw response object
            print(f"🔍 Response type: {type(response)}")
            print(f"🔍 Response repr: {repr(response)}")
            
            # Try to serialize and examine
            try:
                if hasattr(response, 'itemsList'):
                    items = serialize_object(response.itemsList)
                    print(f"🔍 Serialized itemsList: {items}")
                    
                    if items and len(items) > 0:
                        item = items[0]
                        print(f"🔍 Item details:")
                        print(f"   - Name: {item.get('itemName')}")
                        print(f"   - Value: {item.get('value')}")
                        print(f"   - Error: {item.get('error')}")
                        print(f"   - DataType: {item.get('dataType')}")
                        
                        # Check if there's an error in the response
                        if item.get('error'):
                            print(f"❌ ScadaBR returned error: {item.get('error')}")
                            return f"ERROR: {item.get('error')}"
                
                # Also check other attributes
                for attr in dir(response):
                    if not attr.startswith('_'):
                        attr_value = getattr(response, attr, None)
                        if attr_value is not None:
                            print(f"🔍 Response attribute '{attr}': {attr_value}")
                            
            except Exception as ser_err:
                print(f"⚠️ Serialization error: {ser_err}")
            
            print(f"✅ writeStringData call completed")
            return "ACK"
            
        except Exception as e1:
            print(f"⚠️  writeStringData failed: {e1}")
            print(f"🔍 Error details: {repr(e1)}")
            
            # Method 2: Try regular writeData
            try:
                options = {
                    "returnItemValues": True  # Also changed to True here
                }
                
                items_list = [{
                    "itemName": actual_tag,
                    "value": value  # Keep as integer for writeData
                }]
                
                print(f"🔍 Trying writeData with: itemsList={items_list}, options={options}")
                
                response = soap_client.service.writeData(
                    itemsList=items_list,
                    options=options
                )
                
                # DEBUG: Print response for writeData too
                print(f"🔍 writeData Response type: {type(response)}")
                print(f"🔍 writeData Response repr: {repr(response)}")
                
                if hasattr(response, 'itemsList'):
                    try:
                        items = serialize_object(response.itemsList)
                        print(f"🔍 writeData Serialized itemsList: {items}")
                    except:
                        pass
                
                print(f"✅ writeData successful!")
                return "ACK"
            except Exception as e2:
                print(f"⚠️  writeData failed: {e2}")
                print(f"🔍 writeData error details: {repr(e2)}")
                
                # Try one more method: setPointValue if it exists
                try:
                    # Check if setPointValue method exists
                    if hasattr(soap_client.service, 'setPointValue'):
                        print(f"🔍 Trying setPointValue method")
                        response = soap_client.service.setPointValue(
                            pointName=actual_tag,
                            value=str(value)
                        )
                        print(f"✅ setPointValue successful!")
                        return "ACK"
                    else:
                        print(f"⚠️  setPointValue method not available")
                        return f"All write methods failed. Last error: {e2}"
                except Exception as e3:
                    print(f"⚠️  setPointValue also failed: {e3}")
                    return f"All write methods failed. Last error: {e3}"
            
    except Exception as e:
        error_msg = f"Exception in scadabr_write: {str(e)}"
        print(f"🔥 {error_msg}")
        return error_msg

def scadabr_read(tag_path: str):
    try:
        print(f"📖 Attempting to read from ScadaBR - XID: {tag_path}")
        
        actual_tag = TAG_MAPPING.get(tag_path, tag_path)
        print(f"📋 Mapped {tag_path} -> {actual_tag}")
        
        # FIXED: Use maxReturn instead of returnItemValues
        options = {
            "maxReturn": 1  # Changed from returnItemValues to maxReturn
        }
        
        response = soap_client.service.readData(
            itemPathList=[actual_tag],
            options=options
        )
        
        print(f"📋 ScadaBR Read Response: {response}")
        
        # Extract value from response
        if hasattr(response, 'itemsList'):
            items = serialize_object(response.itemsList)
            if items and len(items) > 0:
                item_value = items[0].get('value')
                print(f"✅ Read successful: {item_value}")
                return item_value
        
        print(f"❌ No data returned for {tag_path}")
        return None
        
    except Exception as e:
        print(f"🔥 Read failed: {e}")
        return None
    
# PUBLISH TO RESULT QUEUE
def publish_result(msg: dict, priority: int = 0):
    credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
    params = pika.ConnectionParameters(host=RABBIT_HOST, port=int(os.getenv("RABBIT_PORT")) ,credentials=credentials)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()

    channel.queue_declare(
        queue=RABBIT_RESULT_QUEUE,
        durable=True,
        arguments={"x-max-priority": RABBIT_MAX_PRIORITY}
    )

    properties = pika.BasicProperties(
        delivery_mode=2,  # persistent
        priority=priority,
        content_type="application/json"
    )

    channel.basic_publish(
        exchange="",
        routing_key=RABBIT_RESULT_QUEUE,
        body=json.dumps(msg).encode(),
        properties=properties
    )
    connection.close()



# CONSUMER FROM COMMANDS QUEUE
def consume_commands():
    credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
    params = pika.ConnectionParameters(host=RABBIT_HOST, credentials=credentials)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()

    # Declare commands queue with max priority
    channel.queue_declare(
        queue=COMMANDS_QUEUE,
        durable=True,
        arguments={"x-max-priority": RABBIT_MAX_PRIORITY}
    )

    print("OT PULLER RUNNING — waiting for commands...")

    def callback(ch, method, properties, body):
        cmd = json.loads(body.decode())
        log_entry = {
            "command": cmd
        }

        from pathlib import Path

        LOG_FILE = Path("ot_commands.json")
        if LOG_FILE.exists():
            with open(LOG_FILE, "r+", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
                
                logs.append(log_entry)
                f.seek(0)
                f.truncate()
                json.dump(logs, f, indent=2)

        else:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                json.dump([log_entry], f, indent=2)

        success, error = send_to_splunk(log_entry, sourcetype="ot_execution")
        if not success:
            print(f" Failed to send to splunk: {error}")

        print(f"[OT PULLER] Received:", cmd)

        command_id = cmd.get("command_id")
        tag_path = cmd.get("register_number")
        cmd_type = cmd.get("command_type")
        value = cmd.get("value")
        cmd_priority = RABBIT_MAX_PRIORITY if cmd.get("priority") == "critical" else 0

        try:
            if cmd_type == "r":
                val = scadabr_read(tag_path)
                response = {
                    "command_id": command_id,
                    "type": "r",
                    "status": "success",
                    "value": val,
                    "timestamp": datetime.utcnow().isoformat()
                }

            elif cmd_type == "w":
                ack = scadabr_write(tag_path, value)
                response = {
                    "command_id": command_id,
                    "type": "w",
                    "status": "success" if ack == "ACK" else "error",
                    "ack": ack,
                    "timestamp": datetime.utcnow().isoformat()
                }

            else:
                response = {
                    "command_id": command_id,
                    "type": cmd_type,
                    "status": "error",
                    "error": f"Unknown command type '{cmd_type}'",
                    "timestamp": datetime.utcnow().isoformat()
                }

            RESULT_LOG_FILE = Path("ot_results.json")
            log_entry = {
                "response": response
            }

            if RESULT_LOG_FILE.exists():
                with open(RESULT_LOG_FILE, "r+", encoding="utf-8") as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []


                    logs.append(log_entry)
                    f.seek(0)
                    f.truncate()
                    json.dump(logs, f, indent=2)
            else:
                with open(RESULT_LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump([log_entry], f, indent=2)

            
            success, error = send_to_splunk(log_entry, sourcetype="ot_execution")
            if not success:
                print(f"Failed to send to splunk: {error}")

            publish_result(response, priority=cmd_priority)

        except Exception as e:
            error_response = {
                "command_id": command_id,
                "type": cmd_type,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
            publish_result(error_response, priority=cmd_priority)

        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=COMMANDS_QUEUE, on_message_callback=callback)
    channel.start_consuming()




# FASTAPI STARTUP
@app.on_event("startup")
def start_background_worker():
    worker = threading.Thread(target=consume_commands, daemon=True)
    worker.start()
    print("OT Puller started WOOOO")


@app.get("/")
def root():
    return {"status": "OT Puller running", "soap_wsdl": SCADABR_WSDL}



