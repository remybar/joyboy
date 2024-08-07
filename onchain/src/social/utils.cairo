#[cfg(test)]
pub mod tests {
    use snforge_std::{DeclareResult, ContractClass, declare};

    pub fn declare_contract(contract: ByteArray) -> ContractClass {
        match declare(contract).unwrap() {
            DeclareResult::Success(class) => class,
            DeclareResult::AlreadyDeclared(class) => class
        }
    }
}