use core::ecdsa::check_ecdsa_signature;
use core::traits::BitAnd;
use core::num::traits::Bounded;
use core::num::traits::WideMul as CoreWideMul;

use starknet::SyscallResultTrait;
use starknet::account::Call;


trait Pow2<V, N> {
    #[inline]
    fn pow2(n: N) -> V;
}

impl Pow2u8u8 of Pow2<u8, u8> {
    fn pow2(n: u8) -> u8 {
        match n {
            0 => 0b1,
            1 => 0b10,
            2 => 0b100,
            3 => 0b1000,
            4 => 0b10000,
            5 => 0b100000,
            6 => 0b1000000,
            7 => 0b10000000,
            _ => core::panic_with_felt252('n ouf of range'),
        }
    }
}

impl Pow2u32u32 of Pow2<u32, u32> {
    fn pow2(n: u32) -> u32 {
        match n {
            0 => 0b1,
            1 => 0b10,
            2 => 0b100,
            3 => 0b1000,
            4 => 0b10000,
            5 => 0b100000,
            6 => 0b1000000,
            7 => 0b10000000,
            8 => 0b100000000,
            9 => 0b1000000000,
            10 => 0b10000000000,
            11 => 0b100000000000,
            12 => 0b1000000000000,
            13 => 0b10000000000000,
            14 => 0b100000000000000,
            15 => 0b1000000000000000,
            16 => 0b10000000000000000,
            17 => 0b100000000000000000,
            18 => 0b1000000000000000000,
            19 => 0b10000000000000000000,
            20 => 0b100000000000000000000,
            21 => 0b1000000000000000000000,
            22 => 0b10000000000000000000000,
            23 => 0b100000000000000000000000,
            24 => 0b1000000000000000000000000,
            25 => 0b10000000000000000000000000,
            26 => 0b100000000000000000000000000,
            27 => 0b1000000000000000000000000000,
            28 => 0b10000000000000000000000000000,
            29 => 0b100000000000000000000000000000,
            30 => 0b1000000000000000000000000000000,
            31 => 0b10000000000000000000000000000000,
            _ => core::panic_with_felt252('n ouf of range'),
        }
    }
}


#[inline]
pub fn shr<V, N, +Drop<V>, +Div<V>, +Pow2<V, N>>(v: V, n: N) -> V {
    v / Pow2::pow2(n.into())
}

trait WideMul<V, W> {
    fn wide_mul(x: V, y: V) -> W;
}

impl WideMuluU32 of WideMul<u32, u64> {
    fn wide_mul(x: u32, y: u32) -> u64 {
        CoreWideMul::wide_mul(x, y)
    }
}

impl WideMuluU8 of WideMul<u8, u16> {
    fn wide_mul(x: u8, y: u8) -> u16 {
        CoreWideMul::wide_mul(x, y)
    }
}

#[inline]
pub fn shl<
    V,
    W,
    N,
    +BitAnd<W>,
    +Pow2<V, N>,
    +Bounded<V>,
    +WideMul<V, W>,
    +Into<V, W>,
    +TryInto<W, V>,
    +Drop<V>,
    +Drop<W>,
>(
    x: V, n: N
) -> V {
    (WideMul::wide_mul(x, Pow2::pow2(n)) & Bounded::<V>::MAX.into()).try_into().unwrap()
}

pub const MIN_TRANSACTION_VERSION: u256 = 1;
pub const QUERY_OFFSET: u256 = 0x100000000000000000000000000000000;
// QUERY_OFFSET + TRANSACTION_VERSION
pub const QUERY_VERSION: u256 = 0x100000000000000000000000000000001;

pub fn execute_calls(mut calls: Array<Call>) -> Array<Span<felt252>> {
    let mut res = ArrayTrait::new();
    loop {
        match calls.pop_front() {
            Option::Some(call) => {
                let _res = execute_single_call(call);
                res.append(_res);
            },
            Option::None(_) => { break (); },
        };
    };
    res
}

fn execute_single_call(call: Call) -> Span<felt252> {
    let Call { to, selector, calldata } = call;
    starknet::syscalls::call_contract_syscall(to, selector, calldata).unwrap_syscall()
}

pub fn is_valid_stark_signature(
    msg_hash: felt252, public_key: felt252, signature: Span<felt252>
) -> bool {
    let valid_length = signature.len() == 2;

    if valid_length {
        check_ecdsa_signature(msg_hash, public_key, *signature.at(0_u32), *signature.at(1_u32))
    } else {
        false
    }
}
