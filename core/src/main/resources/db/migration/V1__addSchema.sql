CREATE TABLE  users (
  id VARCHAR(255) NOT NULL ,
  email VARCHAR(255) NOT NULL unique,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(255) NOT NULL check (role in ('ROLE_USER','ROLE_ADMIN')),
  username varchar(255) not null unique,
  PRIMARY KEY (id));