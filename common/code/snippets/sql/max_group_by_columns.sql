-- https://stackoverflow.com/questions/612231/how-can-i-select-rows-with-maxcolumn-value-distinct-by-another-column-in-sql
SELECT tt.*
FROM topten tt
INNER JOIN
    (SELECT home, MAX(datetime) AS MaxDateTime
    FROM topten
    GROUP BY home) groupedtt 
ON tt.home = groupedtt.home 
AND tt.datetime = groupedtt.MaxDateTime
