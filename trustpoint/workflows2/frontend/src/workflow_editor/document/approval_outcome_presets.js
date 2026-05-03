export const APPROVAL_OUTCOME_PRESETS = [
  {
    label: 'approved / rejected',
    approved: 'approved',
    rejected: 'rejected',
    description: 'Explicit approval outcomes.',
    approvedTarget: '$end',
    rejectedTarget: '$reject',
  },
  {
    label: 'ok / fail',
    approved: 'ok',
    rejected: 'fail',
    description: 'Short success/failure routing.',
    approvedTarget: '$end',
    rejectedTarget: '$reject',
  },
  {
    label: 'continue / rejected',
    approved: 'continue',
    rejected: 'rejected',
    description: 'Continue on approval, reject otherwise.',
    approvedTarget: '$end',
    rejectedTarget: '$reject',
  },
];
