function buildExpressionFunctionText(functionName) {
  switch (functionName) {
    case 'add':
      return '${add(vars.a, 1)}';
    case 'sub':
      return '${sub(vars.a, 1)}';
    case 'mul':
      return '${mul(vars.a, 2)}';
    case 'div':
      return '${div(vars.a, 2)}';
    case 'min':
      return '${min(vars.a, vars.b)}';
    case 'max':
      return '${max(vars.a, vars.b)}';
    case 'round':
      return '${round(vars.a)}';
    case 'int':
      return '${int(vars.a)}';
    case 'float':
      return '${float(vars.a)}';
    case 'str':
      return '${str(vars.value)}';
    case 'lower':
      return '${lower(vars.value)}';
    case 'upper':
      return '${upper(vars.value)}';
    case 'concat':
      return '${concat(vars.a, vars.b)}';
    case 'json':
      return '${json(event)}';
    default:
      return `\${${functionName}()}`;
  }
}

export function buildExpressionFunctionInsertion(functionName) {
  return buildExpressionFunctionText(functionName);
}
