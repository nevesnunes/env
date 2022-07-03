-- Declare variables
DECLARE @rc INT
DECLARE @TraceID INT
DECLARE @maxFileSize bigint
DECLARE @fileName NVARCHAR(128)
DECLARE @on bit

-- Set values
SET @maxFileSize = 5
SET @fileName = N'C:\TestTrace'
SET @on = 1

-- Create trace
EXEC @rc = sp_trace_create @TraceID output, 0, @fileName, @maxFileSize, NULL 

-- If error end process
IF (@rc != 0) GOTO error

-- Set the events and data to collect
EXEC sp_trace_setevent @TraceID, 41,  1, @on
EXEC sp_trace_setevent @TraceID, 41, 12, @on
EXEC sp_trace_setevent @TraceID, 41, 13, @on
EXEC sp_trace_setevent @TraceID, 41, 14, @on
EXEC sp_trace_setevent @TraceID, 41, 15, @on
EXEC sp_trace_setevent @TraceID, 41, 16, @on
EXEC sp_trace_setevent @TraceID, 41, 17, @on

-- Set Filters
-- filter1 include databaseId = 6
EXEC sp_trace_setfilter @TraceID, 3, 1, 0, 6
-- filter2 exclude application SQL Profiler
EXEC sp_trace_setfilter @TraceID, 10, 0, 7, N'SQL Profiler'

-- Start the trace
EXEC sp_trace_setstatus @TraceID, 1
 
-- display trace id for future references 
SELECT TraceID=@TraceID 
GOTO finish 

-- error trap
error: 
SELECT ErrorCode=@rc 

-- exit
finish: 
GO
