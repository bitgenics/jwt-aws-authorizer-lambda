'use strict';

const jwt = require('jsonwebtoken');
if(!process.env.JWT_SECRET) {
	console.log('Environment variable JWT_SECRET with the base64 encoded secret key is required');
}
const secret = new Buffer(process.env.JWT_SECRET, 'base64');
const region = process.env.REGION || '*';
const apiId = process.env.API_ID || '*';
const stageId = process.env.STAGE_ID || '*';
const method = process.env.METHOD || '*';
const path = process.env.PATH || '*';

const policy = {
	Version: '2012-10-17',
	Statement: {
		Action: 'execute-api:Invoke',
		Effect: 'Allow',
		Resource: `arn:aws:execute-api:${region}:*:${apiId}/${stageId}/${method}/${path}`
	}
};

module.exports.handler = function( event, context, callback ) {
	if(event.type.toUpperCase() !== 'TOKEN') return callback('Authorisation not of type TOKEN');
	if(!event.authorizationToken || !event.authorizationToken.startsWith('Bearer') ) return callback('No (proper) Authorization header');
	const token = event.authorizationToken.replace(/^Bearer\s*/i, '');
	jwt.verify(token, secret, (err, userInfo) => {
		if(!err && userInfo) {
			callback(undefined, {principalId: userInfo.sub, policyDocument: policy});
		} else {
			callback(err);
		}
	});
	
}