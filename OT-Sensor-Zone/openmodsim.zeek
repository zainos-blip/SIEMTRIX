# Custom OT logging
module OpenModsim;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        orig_bytes: count &log &optional;
        resp_bytes: count &log &optional;
        placeholder1: string &log &optional;
        placeholder2: string &log &optional;
        placeholder3: string &log &optional;
    };
}

event zeek_init() {
    Log::create_stream(OpenModsim::LOG, [$columns=Info, $path="/opt/zeek/logs/current/static_openmodsim"]);
}

event connection_state_remove(c: connection) {
    local ot_ports = set(1502/tcp, 8090/tcp, 5672/tcp, 502/tcp);
    if (c$id$resp_p in ot_ports || c$id$orig_p in ot_ports) {
        local rec: OpenModsim::Info = [
            $ts=network_time(),
            $src_ip=c$id$orig_h,
            $src_port=c$id$orig_p,
            $dst_ip=c$id$resp_h,
            $dst_port=c$id$resp_p,
            $orig_bytes = (c$conn?$orig_bytes ? c$conn$orig_bytes : 0),
            $resp_bytes = (c$conn?$resp_bytes ? c$conn$resp_bytes : 0),
            $placeholder1="-",
            $placeholder2="-",
            $placeholder3="-"
        ];
        Log::write(OpenModsim::LOG, rec);
    }
}
