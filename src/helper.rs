use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

pub fn test_rng() -> StdRng {
    #[rustfmt::skip]
    let seed = [1,0,0,0, 23,0,0,0, 200,1,0,0, 210,30,0,0,
                    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];

    return StdRng::from_seed(seed);
}
