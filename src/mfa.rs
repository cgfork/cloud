use anyhow::{Context, Result, anyhow};
use base32::Alphabet;
use otp::{Generator, HmacSha1, HmacSha256, HmacSha512, TOTP};

use crate::cli::{MfaArgs, OtpAlgorithm};

pub fn generate(args: &MfaArgs) -> Result<String> {
    let secret = base32::decode(Alphabet::Rfc4648 { padding: false }, &args.secret)
        .ok_or_else(|| anyhow!("invalid Base32 TOTP secret"))?;

    match args.algorithm {
        OtpAlgorithm::Sha1 => TOTP::<HmacSha1>::new()
            .with_secret(&secret)
            .with_code_len(args.digits)
            .with_period(args.period)
            .generate()
            .context("failed to generate TOTP code"),
        OtpAlgorithm::Sha256 => TOTP::<HmacSha256>::new()
            .with_secret(&secret)
            .with_code_len(args.digits)
            .with_period(args.period)
            .generate()
            .context("failed to generate TOTP code"),
        OtpAlgorithm::Sha512 => TOTP::<HmacSha512>::new()
            .with_secret(&secret)
            .with_code_len(args.digits)
            .with_period(args.period)
            .generate()
            .context("failed to generate TOTP code"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(algorithm: OtpAlgorithm) -> MfaArgs {
        MfaArgs {
            secret: "TVWKH4OQUHL4BVRF".to_owned(),
            digits: 6,
            period: 30,
            algorithm,
        }
    }

    #[test]
    fn generates_totp_for_each_algorithm() {
        for algorithm in [
            OtpAlgorithm::Sha1,
            OtpAlgorithm::Sha256,
            OtpAlgorithm::Sha512,
        ] {
            let code = generate(&args(algorithm)).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|character| character.is_ascii_digit()));
        }
    }

    #[test]
    fn rejects_invalid_base32_secret() {
        let mut invalid = args(OtpAlgorithm::Sha1);
        invalid.secret = "not base32!".to_owned();

        assert!(generate(&invalid).is_err());
    }
}
