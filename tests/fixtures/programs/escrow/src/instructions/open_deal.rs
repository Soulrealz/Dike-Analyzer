use anchor_lang::prelude::*;

use crate::error::EscrowError;
use crate::state::{Config, Deal};

#[derive(Accounts)]
#[instruction(deal_id: u64)]
pub struct OpenDeal<'info> {
    #[account(mut)]
    pub maker: Signer<'info>,

    #[account(
        init,
        payer = maker,
        space = 8 + 32 + 32 + 8 + 1,
        seeds = [b"deal", maker.key().as_ref(), &deal_id.to_le_bytes()],
        bump
    )]
    pub deal: Account<'info, Deal>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<OpenDeal>, _deal_id: u64, amount: u64, resolver: Pubkey) -> Result<()> {
    require!(amount > 0, EscrowError::InvalidAmount);
    let deal = &mut ctx.accounts.deal;
    deal.maker = ctx.accounts.maker.key();
    deal.resolver = resolver;
    deal.amount = amount;
    deal.bump = ctx.bumps.deal;
    Ok(())
}
