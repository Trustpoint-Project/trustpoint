export const APPROVAL_OUTCOME_PRESETS = [
  {
    label: 'approved / rejected',
    approved: 'approved',
    rejected: 'rejected',
    description: 'Explicit approval outcomes.',
  },
  {
    label: 'ok / fail',
    approved: 'ok',
    rejected: 'fail',
    description: 'Short success/failure routing.',
  },
  {
    label: 'continue / rejected',
    approved: 'continue',
    rejected: 'rejected',
    description: 'Continue on approval, reject otherwise.',
  },
];
