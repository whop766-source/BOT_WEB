const {Pool}=require('pg');
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL&&!/localhost|127\\.0\\.1/.test(process.env.DATABASE_URL)?{rejectUnauthorized:false}:false,max:5,connectionTimeoutMillis:15000});
pool.on('error',e=>console.error('Postgres pool error:',e.message));
module.exports={pool,query:(s,p)=>pool.query(s,p),client:()=>pool.connect()};
