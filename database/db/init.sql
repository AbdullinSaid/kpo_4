CREATE TABLE IF NOT EXISTS "user"
(
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50) UNIQUE  NOT NULL,
    email         VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255)        NOT NULL,
    role          VARCHAR(10)         NOT NULL CHECK (role IN ('customer', 'chef', 'manager')),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION update_change_timestamp_column()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE OR REPLACE TRIGGER update_user_timestamp
    BEFORE UPDATE
    ON "user"
    FOR EACH ROW
EXECUTE PROCEDURE
    update_change_timestamp_column();

CREATE TABLE IF NOT EXISTS session
(
    id            serial PRIMARY KEY,
    user_id       INT          NOT NULL,
    session_token VARCHAR(255) NOT NULL,
    expires_at    TIMESTAMP    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES "user" (id)
);


CREATE TABLE IF NOT EXISTS dish
(
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(100)   NOT NULL,
    dish_description  TEXT,
    price        DECIMAL(10, 2) NOT NULL,
    quantity     INT            NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE OR REPLACE FUNCTION update_change_timestamp_column()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE OR REPLACE TRIGGER update_dish_timestamp
    BEFORE UPDATE
    ON "dish"
    FOR EACH ROW
EXECUTE PROCEDURE
    update_change_timestamp_column();

CREATE TABLE IF NOT EXISTS "order"
(
    id               SERIAL PRIMARY KEY,
    user_id          INT         NOT NULL,
    status           VARCHAR(50) NOT NULL,
    special_requests TEXT,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES "user" (id)
);
CREATE OR REPLACE FUNCTION update_change_timestamp_column()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE OR REPLACE TRIGGER update_order_timestamp
    BEFORE UPDATE
    ON "order"
    FOR EACH ROW
EXECUTE PROCEDURE
    update_change_timestamp_column();


CREATE TABLE order_dish
(
    id       SERIAL PRIMARY KEY,
    order_id INT            NOT NULL,
    dish_id  INT            NOT NULL,
    quantity INT            NOT NULL,
    price    DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES "order" (id),
    FOREIGN KEY (dish_id) REFERENCES dish (id)
);


