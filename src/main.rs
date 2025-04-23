use base64::Engine;
use verification::verification::{verify_skip, verify_step};
mod consts;
mod input;
pub mod types;
pub mod utils;
pub mod verification;

#[tokio::main]
async fn main() {
    const MAX_VALIDATOR_SET_SIZE: usize = 100;
    let trusted_header: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode("HYyCY04wxwiXEAqonHNfnMfqgjIjgovK/wSyLpfIb4A=")
        .unwrap()
        .try_into()
        .unwrap();
    let trusted_height = 28122519u64;
    let target_height = 28122520u64;
    let mut input_data_fetcher = input::InputDataFetcher::default();
    /*let skip_inputs = input_data_fetcher
    .get_skip_inputs::<MAX_VALIDATOR_SET_SIZE>(
        trusted_height,
        trusted_header.to_vec(),
        target_height,
    )
    .await;*/
    //verify_skip(&skip_inputs).unwrap();

    let step_inputs = input_data_fetcher
        .get_step_inputs::<MAX_VALIDATOR_SET_SIZE>(trusted_height, trusted_header.to_vec())
        .await;
    verify_step(&step_inputs, trusted_header.to_vec()).unwrap();
}
