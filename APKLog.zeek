@load base/frameworks/files
@load base/frameworks/logging
@load base/protocols/http

module APKLog;

export {
    # 定义APK下载日志记录类型
    type Info: record {
        ts:         time    &log;  # 时间戳
        uid:        string  &log;  # 唯一连接ID
        id:         conn_id &log;  # 连接信息
        host:       string  &log;  # 目标主机
        uri:        string  &log;  # 请求URI
        url:        string  &log;  # 完整URL
        filename:   string  &log;  # 文件名
        mime_type:  string  &log;  # MIME类型
        file_size:  count   &log;  # 文件大小
        md5:        string  &log;  # MD5哈希
        sha1:       string  &log;  # SHA1哈希
        sha256:     string  &log;  # SHA256哈希
    };

    # 定义日志流
    global log_apk: event(rec: Info);
}

# 创建日志写入器
global apk_log = Log::get_stream(APKLog::Info, [$columns=Info]);

# 用于跟踪APK文件的哈希表
global apk_files: table[string] of Info &create_expire=1day;

event file_new(f: fa_file) {
    # 检查是否为APK文件（通过文件名或MIME类型）
    if ( (f?$info && f$info?$filename && f$info$filename == /\.apk$/i) ||
         (f?$info && f$info?$mime_type && f$info$mime_type == "application/vnd.android.package-archive") )
    {
        local rec: APKLog::Info;
        rec$ts = network_time();
        rec$filename = f$info$filename;
        rec$mime_type = f$info$mime_type;
        
        # 存储文件信息以便后续补充连接信息
        apk_files[f$id] = rec;
    }
}

event file_state_remove(f: fa_file) {
    if (f$id in apk_files) {
        local rec = apk_files[f$id];
        
        # 获取文件哈希
        if (f?$info && f$info?$md5) rec$md5 = f$info$md5;
        if (f?$info && f$info?$sha1) rec$sha1 = f$info$sha1;
        if (f?$info && f$info?$sha256) rec$sha256 = f$info$sha256;
        if (f?$info && f$info?$size) rec$file_size = f$info$size;

        # 获取连接信息
        if (|f$info$conn_uids| > 0) {
            local conn_uid = f$info$conn_uids[0];
            if (conn_uid in connection_table) {
                local c = connection_table[conn_uid];
                rec$uid = conn_uid;
                rec$id = c$id;
                
                # 如果是HTTP连接，构建完整URL
                if (f$source == "HTTP" && c?$http) {
                    rec$host = c$http$host;
                    rec$uri = c$http$uri;
                    
                    # 构建完整URL
                    if (c$http$uri != "" && /^https?:\/\// in c$http$uri) {
                        rec$url = c$http$uri;
                    } else {
                        local protocol = (c?$ssl) ? "https" : "http";
                        rec$url = fmt("%s://%s%s", protocol, c$http$host, c$http$uri);
                    }
                }
            }
        }

        # 写入日志
        Log::write(apk_log, rec);
        delete apk_files[f$id];
    }
}
