mod consts;
mod input;
pub mod types;
pub mod utils;
pub mod verification;

#[cfg(test)]
mod tests {
    use base64::Engine;

    use crate::{
        input,
        verification::verification::{verify_skip, verify_step},
    };

    #[tokio::test]
    async fn test_verify_step() {
        const MAX_VALIDATOR_SET_SIZE: usize = 100;
        let trusted_header: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode("HYyCY04wxwiXEAqonHNfnMfqgjIjgovK/wSyLpfIb4A=")
            .unwrap()
            .try_into()
            .unwrap();
        let trusted_height = 28122519u64;
        let mut input_data_fetcher = input::InputDataFetcher::default();
        let step_inputs = input_data_fetcher
            .get_step_inputs::<MAX_VALIDATOR_SET_SIZE>(trusted_height, trusted_header.to_vec())
            .await;
        verify_step(&step_inputs, trusted_header.to_vec()).unwrap();
    }

    #[tokio::test]
    async fn test_verify_skip() {
        const MAX_VALIDATOR_SET_SIZE: usize = 100;
        let trusted_header: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode("HYyCY04wxwiXEAqonHNfnMfqgjIjgovK/wSyLpfIb4A=")
            .unwrap()
            .try_into()
            .unwrap();
        let trusted_height = 28122519u64;
        let target_height = 28122525u64;
        let mut input_data_fetcher = input::InputDataFetcher::default();
        let skip_inputs = input_data_fetcher
            .get_skip_inputs::<MAX_VALIDATOR_SET_SIZE>(
                trusted_height,
                trusted_header.to_vec(),
                target_height,
            )
            .await;
        verify_skip(&skip_inputs).unwrap();
    }
}
