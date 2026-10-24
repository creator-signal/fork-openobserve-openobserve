use std::{
    io::{Read, Seek},
    ops::{Deref, DerefMut},
    path::Path,
};

use zip::result::ZipResult;

#[derive(Clone, Debug)]
pub struct ZipArchive<R: Read + Seek>(zip::ZipArchive<R>);

impl<R: Read + Seek> Deref for ZipArchive<R> {
    type Target = zip::ZipArchive<R>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<R: Read + Seek> DerefMut for ZipArchive<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<R: Read + Seek> ZipArchive<R> {
    pub fn new(reader: R) -> ZipResult<Self> {
        zip::ZipArchive::new(reader).map(Self)
    }
    /// Use the patched ZIP implementation's confined symlink extraction and
    /// permission handling rather than the historical unchecked custom copier.
    pub fn extract<P: AsRef<Path>>(&mut self, directory: P) -> ZipResult<()> {
        self.0.extract(directory)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;

    use super::*;

    fn fixture(name: &str, symlink: Option<&str>, mode: u32) -> Cursor<Vec<u8>> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().unix_permissions(mode);
        if let Some(target) = symlink {
            writer.add_symlink(name, target, options).unwrap();
        } else {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"synthetic-archive-content").unwrap();
        }
        writer.finish().unwrap()
    }

    #[test]
    fn normal_browser_archive_extracts() {
        let output = tempfile::tempdir().unwrap();
        let mut archive = ZipArchive::new(fixture("browser/chrome", None, 0o755)).unwrap();
        archive.extract(output.path()).unwrap();
        assert_eq!(
            std::fs::read(output.path().join("browser/chrome")).unwrap(),
            b"synthetic-archive-content"
        );
    }

    #[test]
    fn parent_path_cannot_write_outside_destination() {
        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("extracted");
        let mut archive = ZipArchive::new(fixture("../outside", None, 0o644)).unwrap();
        let _ = archive.extract(&output);
        assert!(!parent.path().join("outside").exists());
    }

    #[cfg(unix)]
    #[test]
    fn escaping_symlink_is_rejected() {
        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("extracted");
        let mut archive = ZipArchive::new(fixture("escape", Some("../outside"), 0o777)).unwrap();
        assert!(archive.extract(&output).is_err());
        assert!(!output.join("escape").exists());
        assert!(!parent.path().join("outside").exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_cannot_redirect_writes_or_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let parent = tempfile::tempdir().unwrap();
        let output = parent.path().join("extracted");
        std::fs::create_dir(&output).unwrap();
        let outside = parent.path().join("outside");
        std::fs::write(&outside, b"retained-fixture").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&outside, output.join("escape")).unwrap();
        let mut archive = ZipArchive::new(fixture("escape", None, 0o777)).unwrap();
        assert!(archive.extract(&output).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"retained-fixture");
        assert_eq!(
            std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn extraction_removes_setuid_and_setgid_bits() {
        use std::os::unix::fs::PermissionsExt;
        let output = tempfile::tempdir().unwrap();
        let mut bytes = fixture("chrome", None, 0o755).into_inner();
        let central = bytes.windows(4).position(|b| b == b"PK\x01\x02").unwrap();
        bytes[central + 38..central + 42].copy_from_slice(&((0o106755_u32) << 16).to_le_bytes());
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        archive.extract(output.path()).unwrap();
        let mode = std::fs::metadata(output.path().join("chrome"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o6000, 0);
    }

    #[cfg(unix)]
    #[test]
    fn internal_browser_symlink_is_preserved() {
        let output = tempfile::tempdir().unwrap();
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().unix_permissions(0o755);
        writer.start_file("browser/chrome", options).unwrap();
        writer.write_all(b"synthetic-browser").unwrap();
        writer
            .add_symlink("browser/current", "chrome", options)
            .unwrap();
        let mut archive = ZipArchive::new(writer.finish().unwrap()).unwrap();
        archive.extract(output.path()).unwrap();
        assert_eq!(
            std::fs::read(output.path().join("browser/current")).unwrap(),
            b"synthetic-browser"
        );
    }
}
