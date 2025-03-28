const getSearchQuery = (model, searchFields, search) =>
  searchFields
    .filter(
      (field) =>
        !(
          model.schema.paths[field].instance === 'Number' &&
          // eslint-disable-next-line no-restricted-globals
          isNaN(parseInt(search, 10))
        ),
    )
    .map((field) =>
      model.schema.paths[field].instance === 'Number'
        ? { [field]: parseInt(search, 10) }
        : { [field]: new RegExp(search, 'gi') },
    );

const getSortQuery = (sort) =>
  sort
    ? JSON.parse(
        `{${sort
          .map((element) => {
            const field = element.substring(0, element.lastIndexOf('_'));
            const value =
              element.substring(element.lastIndexOf('_') + 1) === 'asc'
                ? 1
                : -1;
            return `"${field}":${value}`;
          })
          .join(',')}}`,
      )
    : { _id: 1 };

const getSelectQuery = (fields) =>
  JSON.parse(`{${fields.map((element) => `"${element}":1`).join(',')}}`);

// TODO: refactor
const getDateQuery = (dateField, startDate, endDate) => {
  if (startDate && endDate)
    return {
      [dateField]: { $gte: new Date(startDate), $lte: new Date(endDate) },
    };

  if (startDate && !endDate)
    return {
      [dateField]: { $gte: new Date(startDate) },
    };

  if (!startDate && endDate)
    return {
      [dateField]: { $lte: new Date(endDate) },
    };

  return {};
};

module.exports = { getSearchQuery, getSortQuery, getSelectQuery, getDateQuery };
