-- https://stackoverflow.com/questions/12362085/get-the-field-with-longest-string-for-same-id-value
SELECT id,
       test_data
FROM
    ( SELECT id,
             test_data,
             row_number() over(PARTITION BY id
                               ORDER BY length(test_data) DESC) AS rnum
     FROM test)
WHERE rnum=1
