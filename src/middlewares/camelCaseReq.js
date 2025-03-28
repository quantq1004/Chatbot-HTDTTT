import camelcaseKeys from 'camelcase-keys';

export default function camelCaseReq(req, res, next) {
  if (req.body) {
    req.body = camelcaseKeys(req.body, { deep: true });
  }
  next();
}
