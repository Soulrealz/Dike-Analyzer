use anchor_lang::prelude::*;

#[error_code]
pub enum EscrowError {
    #[msg("caller is not authorized")]
    Unauthorized,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("amount must be greater than zero")]
    InvalidAmount,
}
