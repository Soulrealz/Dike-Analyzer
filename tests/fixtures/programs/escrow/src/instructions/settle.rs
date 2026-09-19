use anchor_lang::prelude::*;

use crate::error::EscrowError;
use crate::state::{Config, Deal};

/// The sibling-pin shape. `maker` is an `UncheckedAccount` and is never
/// declared with a pin of its own — its identity is fixed by `deal`, which
/// derives from it and stores it. Substituting another `maker` derives a
/// `deal` that does not exist or belongs to that other maker.
#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned by `deal`'s seeds and by the constraint below.
    pub maker: UncheckedAccount<'info>,

    #[account(
        mut,
        close = caller,
        seeds = [b"deal", maker.key().as_ref()],
        bump = deal.bump,
        constraint = deal.maker == maker.key() @ EscrowError::Unauthorized,
    )]
    pub deal: Account<'info, Deal>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
}

pub fn handler(ctx: Context<Settle>, amount: u64) -> Result<()> {
    let deal = &mut ctx.accounts.deal;
    deal.amount = deal.amount.checked_sub(amount).ok_or(EscrowError::Overflow)?;
    Ok(())
}
