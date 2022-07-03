-- Connect
-- sudo -u postgres psql

-- Counting multiple distinct columns

SELECT count(*)
FROM
    (SELECT DISTINCT a,
                     b
     FROM t) AS t2;

-- Correlation
--
-- Reference:
-- https://www.postgresql.org/docs/9.4/functions-aggregate.html#FUNCTIONS-AGGREGATE-STATISTICS-TABLE

SELECT corr("Amount", "Activities") AS "Corr Coef Using PGSQL Func"
FROM
    (SELECT date_trunc('day', p.payment_date)::DATE AS "Day",
            sum(p.amount) AS "Amount",
            count(DISTINCT a.activity_id) AS "Activities"
     FROM public.payments p
     INNER JOIN public.subscriptions s ON p.subscription_id = s.subscription_id
     INNER JOIN public.users u ON s.user_id = u.user_id
     INNER JOIN public.activity a ON a.user_id = u.user_id
     GROUP BY 1) AS a
