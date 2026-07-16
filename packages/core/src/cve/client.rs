use std::path::Path;

use crate::cve::database::CveDatabase;

/// Загрузить CVE базу из MessagePack файла.
pub fn load_cve_db(path: &Path) -> CveDatabase {
    if !path.exists() {
        return CveDatabase::default();
    }
    match std::fs::read(path) {
        Ok(data) => rmp_serde::from_slice(&data).unwrap_or_default(),
        Err(_) => CveDatabase::default(),
    }
}

/// Сохранить CVE базу в MessagePack файл.
pub fn save_cve_db(db: &CveDatabase, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data =
        rmp_serde::to_vec(db).map_err(std::io::Error::other)?;
    std::fs::write(path, &data)?;
    Ok(())
}

/// CPE → сервис mapping для запросов к CIRCL API
pub const CPE_MAPPING: &[(&str, &[&str])] = &[
    ("ssh", &["cpe:2.3:a:openbsd:openssh"]),
    (
        "http",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:nginx:nginx",
            "cpe:2.3:a:apache:tomcat",
            "cpe:2.3:a:microsoft:internet_information_services",
        ],
    ),
    (
        "https",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:nginx:nginx",
            "cpe:2.3:a:microsoft:internet_information_services",
        ],
    ),
    ("ftp", &["cpe:2.3:a:filezilla:filezilla_ftp_server"]),
    ("mysql", &["cpe:2.3:a:oracle:mysql"]),
    ("mssql", &["cpe:2.3:a:microsoft:sql_server"]),
    ("postgresql", &["cpe:2.3:a:postgresql:postgresql"]),
    ("redis", &["cpe:2.3:a:redis:redis"]),
    ("mongodb", &["cpe:2.3:a:mongodb:mongodb"]),
    ("elasticsearch", &["cpe:2.3:a:elastic:elasticsearch"]),
    ("oracle", &["cpe:2.3:a:oracle:oracle_database"]),
    ("smb", &["cpe:2.3:a:microsoft:windows_smb"]),
    ("rdp", &["cpe:2.3:a:microsoft:remote_desktop"]),
    ("vnc", &["cpe:2.3:a:realvnc:vnc"]),
    ("nfs", &["cpe:2.3:a:linux:nfs-utils"]),
    ("dns", &["cpe:2.3:a:isc:bind"]),
    ("telnet", &["cpe:2.3:a:mit:telnet"]),
    ("netbios", &["cpe:2.3:a:microsoft:netbios"]),
    ("msrpc", &["cpe:2.3:a:microsoft:rpc"]),
    ("imap", &["cpe:2.3:a:cyrus:imap"]),
    ("pop3", &["cpe:2.3:a:cyrus:pop3d"]),
    (
        "smtp",
        &[
            "cpe:2.3:a:postfix:postfix",
            "cpe:2.3:a:exim:exim",
        ],
    ),
    (
        "http-proxy",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:squid-cache:squid",
        ],
    ),
    (
        "https-alt",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:nginx:nginx",
        ],
    ),
    (
        "http-alt",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:nginx:nginx",
        ],
    ),
];

/// Получить CPE для сервиса (известные имена)
pub fn get_cpe_for_service(service: &str) -> Vec<&'static str> {
    let svc = service.to_lowercase();
    let svc = match svc.as_str() {
        "http-alt" | "http-proxy" => "http",
        "https-alt" => "https",
        other => other,
    };
    CPE_MAPPING
        .iter()
        .find(|(name, _)| *name == svc)
        .map(|(_, cpes)| cpes.to_vec())
        .unwrap_or_default()
}
