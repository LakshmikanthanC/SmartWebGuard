const randIP = () => Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join(".");
const randPort = () => Math.floor(Math.random() * 65535) + 1;

const genTraffic = () => {
  const isAtk = Math.random() < 0.3;
  const proto = ["tcp", "udp", "icmp"];
  const svc = isAtk ? ["http", "private", "ecr_i", "smtp", "other"] : ["http", "https", "dns", "ssh", "ftp"];
  const flg = isAtk ? ["SF", "S0", "REJ", "RSTO"] : ["SF", "S0", "REJ"];

  return {
    duration: isAtk ? Math.random() * 5 : Math.random() * 60,
    protocol_type: proto[Math.floor(Math.random() * proto.length)],
    service: svc[Math.floor(Math.random() * svc.length)],
    flag: flg[Math.floor(Math.random() * flg.length)],
    src_bytes: Math.floor(Math.random() * (isAtk ? 50000 : 2000)),
    dst_bytes: Math.floor(Math.random() * 5000),
    land: isAtk && Math.random() < 0.1 ? 1 : 0,
    wrong_fragment: isAtk ? Math.floor(Math.random() * 3) : 0,
    urgent: 0, hot: Math.floor(Math.random() * (isAtk ? 10 : 2)),
    num_failed_logins: isAtk ? Math.floor(Math.random() * 5) : 0,
    logged_in: Math.random() < 0.7 ? 1 : 0,
    num_compromised: isAtk ? Math.floor(Math.random() * 3) : 0,
    root_shell: isAtk && Math.random() < 0.15 ? 1 : 0,
    su_attempted: 0, num_root: 0,
    num_file_creations: Math.floor(Math.random() * 2),
    num_shells: 0, num_access_files: 0, num_outbound_cmds: 0,
    is_host_login: 0, is_guest_login: 0,
    count: isAtk ? Math.floor(Math.random() * 500 + 50) : Math.floor(Math.random() * 50),
    srv_count: Math.floor(Math.random() * 30),
    serror_rate: isAtk ? Math.random() * 0.8 + 0.2 : Math.random() * 0.1,
    srv_serror_rate: isAtk ? Math.random() * 0.8 + 0.2 : Math.random() * 0.1,
    rerror_rate: Math.random() * 0.3, srv_rerror_rate: Math.random() * 0.3,
    same_srv_rate: isAtk ? Math.random() * 0.5 : Math.random() * 0.5 + 0.5,
    diff_srv_rate: Math.random() * 0.5, srv_diff_host_rate: Math.random() * 0.5,
    dst_host_count: Math.floor(Math.random() * 255) + 1,
    dst_host_srv_count: Math.floor(Math.random() * 255) + 1,
    dst_host_same_srv_rate: Math.random(), dst_host_diff_srv_rate: Math.random(),
    dst_host_same_src_port_rate: Math.random(), dst_host_srv_diff_host_rate: Math.random(),
    dst_host_serror_rate: isAtk ? Math.random() * 0.8 + 0.2 : Math.random() * 0.1,
    dst_host_srv_serror_rate: isAtk ? Math.random() * 0.8 + 0.2 : Math.random() * 0.1,
    dst_host_rerror_rate: Math.random() * 0.3, dst_host_srv_rerror_rate: Math.random() * 0.3,
  };
};

module.exports = { randIP, randPort, genTraffic };