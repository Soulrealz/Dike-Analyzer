use anchor_lang::prelude::*;

#[account]
pub struct Config {
    /// The live authority. Every privileged handler binds the caller to this.
    pub admin: Pubkey,
    /// The staged authority: written by `nominate_admin`, and the authority
    /// only inside `accept_admin`. A handler gated on `admin` is not acting as
    /// this one, which is the distinction that cost four false positives
    /// before the detector learned it.
    pub pending_admin: Pubkey,
    pub fee_bps: u16,
    pub bump: u8,
}

#[account]
pub struct Deal {
    pub maker: Pubkey,
    /// The third party allowed to resolve this deal. Not an authority name,
    /// so `missing-authority-binding` does not watch it — the only thing
    /// standing between this field and any caller is the guard in `resolve`.
    pub resolver: Pubkey,
    pub amount: u64,
    pub bump: u8,
}
