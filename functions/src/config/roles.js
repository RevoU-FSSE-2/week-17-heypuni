const allRoles = {
  user: ['getProductAll', 'manageProducts'],
  admin: ['getUsers', 'manageUsers', 'getProductAll', 'manageProducts'],
};

const roles = Object.keys(allRoles);
const roleRights = new Map(Object.entries(allRoles));

module.exports = {
  roles,
  roleRights,
};
