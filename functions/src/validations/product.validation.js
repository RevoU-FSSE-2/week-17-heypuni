/* eslint-disable prettier/prettier */
const Joi = require('joi');
const { objectId } = require('./custom.validation');

const createProduct = {
  body: Joi.object().keys({
    title: Joi.string().required(),
    description: Joi.string().required(),
    priority: Joi.string().required(),
    dueDate: Joi.string().required(),
  }),
};

const getProductAll = {
  query: Joi.object().keys({
    title: Joi.string(),
    description: Joi.string(),
    priority: Joi.string(),
    dueDate: Joi.string(),
    sortBy: Joi.string(),
    limit: Joi.number().integer(),
    page: Joi.number().integer(),
  }),
};

const getProduct = {
  params: Joi.object().keys({
    productId: Joi.string().custom(objectId),
  }),
};

const updateProduct = {
  params: Joi.object().keys({
    productId: Joi.required().custom(objectId),
  }),
    body: Joi.object()
        .keys({
        title: Joi.string(),
        description: Joi.string(),
        priority: Joi.string(),
        dueDate: Joi.string(),
        })
        .min(1),
};

const deleteProduct = {
  params: Joi.object().keys({
    productId: Joi.string().custom(objectId),
  }),
};

module.exports = {
  createProduct,
  getProductAll,
  getProduct,
  updateProduct,
  deleteProduct,
};