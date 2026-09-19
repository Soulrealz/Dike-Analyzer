use anchor_lang::prelude::*;

use crate::error::EscrowError;
use crate::state::Config;

/// Step two, and the only handler in which `pending_admin` is the authority.
/// It is bound here and nowhere else, which is the whole point of staging it.
#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    pub pending_admin: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        constraint = config.pending_admin == pending_admin.key() @ EscrowError::Unauthorized,
    )]
    pub config: Account<'info, Config>,
}

pub fn handler(ctx: Context<AcceptAdmin>) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.admin = config.pending_admin;
    config.pending_admin = Pubkey::default();
    Ok(())
}
