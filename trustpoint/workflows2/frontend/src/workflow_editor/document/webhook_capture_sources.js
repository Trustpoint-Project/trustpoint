export const WEBHOOK_CAPTURE_SOURCE_OPTIONS = [
  {
    value: 'status_code',
    description: 'HTTP response status code.',
  },
  {
    value: 'body',
    description: 'Entire parsed response body.',
  },
  {
    value: 'headers',
    description: 'All response headers as a mapping.',
  },
  {
    value: 'headers.x-request-id',
    description: 'A single response header by name.',
  },
  {
    value: 'body.some_value',
    description: 'A nested response body field by dotted path.',
  },
];
