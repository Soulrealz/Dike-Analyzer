use anchor_lang::prelude::*;

use crate::error::EscrowError;
use crate::state::Deal;

#[derive(Accounts)]
pub struct Fund<'info> {
    #[account(mut)]
    pub maker: Signer<'info>,

    #[account(
        mut,
        has_one = maker @ EscrowError::Unauthorized,
        seeds = [b"deal", maker.key().as_ref()],
        bump = deal.bump,
    )]
    pub deal: Account<'info, Deal>,
}

pub fn handler(ctx: Context<Fund>, amount: u64) -> Result<()> {
    require!(amount > 0, EscrowError::InvalidAmount);
    let deal = &mut ctx.accounts.deal;
    deal.amount = deal.amount.checked_add(amount).ok_or(EscrowError::Overflow)?;
    Ok(())
}
