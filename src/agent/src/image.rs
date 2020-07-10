// Copyright (c) 2020 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::create_dir_all;
use std::path::Path;
use std::process::Command;

use base64;

use protocols::types::AuthConfig;
use rustjail::errors::*;

const SKOPEO_PATH: &str = "/bin/skopeo";
const UMOCI_PATH: &str = "/bin/umoci";

const IMAGE_PARENT_DIR: &str = "/var/lib/kata-containers/images/";
const DEFAULT_IMAGE_TAG: &str = "latest";

// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger().new(o!("subsystem" => "image"))
    };
}

#[derive(Clone)]
pub struct ImageManager {
    puller: String,
    unpacker: String,
    dir: String,
}

impl ImageManager {
    pub fn new() -> Self {
        ImageManager {
            puller: SKOPEO_PATH.to_string(),
            unpacker: UMOCI_PATH.to_string(),
            dir: IMAGE_PARENT_DIR.to_string(),
        }
    }

    pub fn pull_image(&self, image: &str, path: &str, auth: &AuthConfig) -> Result<String> {
        info!(sl!(), "pull image {} to {}", image, path);
        // TODO: check local images first
        self.download_image(image, auth)?;
        self.unpack_image(image, path)?;
        Ok(image.to_string())
    }

    // An image <name:tag> will be downloaded to local path dir/name-tag:tag
    fn download_image(&self, image: &str, auth: &AuthConfig) -> Result<()> {
        let (path, name, tag) = self.parse_image(image)?;
        let parent = Path::new(&path).parent().unwrap_or(Path::new(&self.dir));
        if !parent.exists() {
            create_dir_all(&parent)?;
        }

        let mut cmd = Command::new(&self.puller);
        cmd.arg("--insecure-policy")
            .arg("copy")
            .arg("docker://".to_string() + name + ":" + tag)
            .arg("oci:".to_string() + &path + ":" + tag);

        // Apply auth, priority
        // 1. username + password
        // 2. identity token
        // 3. auth which is base64 encoded username + password, separated by ":"
        // 4. registry token, unsupported by containerd yet
        if auth.get_username().len() > 0 {
            let auth_args = if auth.get_password().len() > 0 {
                auth.get_username().to_string() + ":" + auth.get_password()
            } else {
                auth.get_username().to_string()
            };
            cmd.arg("--src-creds").arg(auth_args);
        } else if auth.get_identity_token().len() > 0 {
            // TODO: unsupported by skopeo yet
        } else if auth.get_auth().len() > 0 {
            let (username, password) = self.parse_identity(auth.get_auth())?;
            cmd.arg("--src-creds").arg(username + ":" + &password);
        } else if auth.get_registry_token().len() > 0 {
            // TODO: unsupported by containerd yet
        }

        cmd.output()?;
        Ok(())
    }

    fn unpack_image(&self, image: &str, path: &str) -> Result<()> {
        let (image_path, _, tag) = self.parse_image(image)?;
        Command::new(&self.unpacker)
            .arg("unpack")
            .arg("--rootless")
            .arg("--image")
            .arg(image_path + ":" + tag)
            .arg(path)
            .output()?;
        Ok(())
    }

    // Convert an image name to a local image path with format dir/name-tag:tag
    fn parse_image<'a>(&self, image: &'a str) -> Result<(String, &'a str, &'a str)> {
        let v: Vec<&str> = image.split(':').collect();
        let mut path = self.dir.clone();
        path.push_str("/");
        let (name, tag) = match v.len() {
            1 => (image, DEFAULT_IMAGE_TAG),
            2 => (v[0], v[1]),
            _ => {
                return Err(
                    ErrorKind::ErrorCode(format!("invalid image format {}", image))
                        .to_string()
                        .into(),
                )
            }
        };

        path.push_str(name);
        path.push_str("-");
        path.push_str(tag);
        Ok((path, name, tag))
    }

    fn parse_identity(&self, identity: &str) -> Result<(String, String)> {
        let id = base64::decode(identity.as_bytes()).map_err(|e| {
            ErrorKind::ErrorCode(format!("invalid auth identity token:{}", e).to_string())
        })?;
        let id = String::from_utf8_lossy(&id);
        let v: Vec<_> = id.split(':').collect();
        if v.len() != 2 {
            return Err(ErrorKind::ErrorCode("invalid identity token".to_string()).into());
        }
        Ok((v[0].to_string(), v[1].trim().to_string()))
    }
}
