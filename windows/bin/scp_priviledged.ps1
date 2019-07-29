# key = ${dir}\.ssh\foo.ppk

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string] $ssh_host,
    [Parameter(Mandatory=$true)] [string] $id,
    [Parameter(Mandatory=$true)] [string] $key,
    [Parameter(Mandatory=$true)] [string[]] $target_files
)

foreach ($target_file in $target_files) {
    $target_file_split = ${target_file}.split("/")
    $target_file_name = $target_file.split("/")[($target_file_split.count - 1)]
    $target_dir = $target_file.split("/")[0..($target_file_split.count - 2)] -join '/'
    $target_dir_win = -join(${ssh_host}, ${target_dir}) -replace '\/','\'
    New-Item ${target_dir_win} -ItemType Directory -Force

    # Workaround intermitent error:
    # ssh_init: gethostbyname: unknown error
    $last_exit_code = $false
    do {
        & ${dir}\opt\putty\plink -no-antispoof -i ${key} "${id}" `
            sudo su -c "'cp "${target_file}" /tmp/1; chmod 777 /tmp/1'"
        $last_exit_code = $?
        sleep 5
    } while ($last_exit_code -eq $false)

    $last_exit_code = $false
    do {
        & ${dir}\opt\putty\pscp -i ${key} `
            ${id}:/tmp/1 ${target_dir_win}\${target_file_name}
        $last_exit_code = $?
        sleep 5
    } while ($last_exit_code -eq $false)
}
& ${dir}\opt\putty\plink -no-antispoof -i ${key} ${id} `
    sudo su -c "'rm -f /tmp/1'"
