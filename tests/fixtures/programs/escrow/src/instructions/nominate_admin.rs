use anchor_lang::prelude::*;

use crate::error::EscrowError;
use crate::state::Config;

/// Step one of a two-step transfer. The caller is the *live* admin, bound by
/// `has_one`; the nominee arrives as a value, not an account, because nothing
/// about it is authenticated here.
#[derive(Accounts)]
pub struct NominateAdmin<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        has_one = admin @ EscrowError::Unauthorized,
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,
}

pub fn handler(ctx: Context<NominateAdmin>, new_admin: Pubkey) -> Result<()> {
    ctx.accounts.config.pending_admin = new_admin;
    Ok(())
}
