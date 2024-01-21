openssl ecparam -out usiem_syslog_ca.key -name prime256v1 -genkey
openssl req -new -sha256 -key usiem_syslog_ca.key -out usiem_syslog_ca.csr
openssl x509 -req -sha256 -days 6000 -in usiem_syslog_ca.csr -signkey usiem_syslog_ca.key -out usiem_syslog_ca.crt
openssl ecparam -out usiem_syslog_test.key -name prime256v1 -genkey
openssl req -new -sha256 -key usiem_syslog_test.key -out usiem_syslog_test_21234.csr
openssl x509 -req -in usiem_syslog_test_21234.csr -CA  usiem_syslog_ca.crt -CAkey usiem_syslog_ca.key -CAcreateserial -out usiem_syslog_test_21234.crt -days 6000 -sha256 -extfile usiem_syslog_test_21234.ext