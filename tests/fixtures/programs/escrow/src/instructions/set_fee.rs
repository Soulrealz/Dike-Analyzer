use anchor_lang::prelude::*;

use crate::error::EscrowError;
use crate::state::Config;

/// The binding written from the signer's side. `address = config.admin` is
/// exactly what `has_one = admin` on the config would say, and Anchor treats
/// them alike — a detector that reads only the config declaration sees one of
/// the two.
#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut, address = config.admin @ EscrowError::Unauthorized)]
    pub admin: Signer<'info>,

    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
}

pub fn handler(ctx: Context<SetFee>, fee_bps: u16) -> Result<()> {
    ctx.accounts.config.fee_bps = fee_bps;
    Ok(())
}
