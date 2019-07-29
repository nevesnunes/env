https://github.com/mattn/gist-vim/issues/48

This is not a permissions problem, and windows DOES in fact unset read-only. It's just a GUI bug that it thinks the bit is set. If you don't believe me, bring up the command prompt, cd to where the folder is, then do: dir /a:r. The folder you turned read-only off will not appear, because it really IS off.

The problem is really with the system() call. Just doing this from within vim will reproduce it:
:echo system("echo hi")

The problem is because some shell like cygwin shell is being used. I put these commands at the top of my \_vimrc file to solve the problem:
set shell=cmd
set shellcmdflag=/c

This problem is solved now. I am not certain why this fixes it, because it seems like a race condition where the tmp file is created and closed before the process is done using it. The tmp file is in fact created successfully (I saw this with procmon), but it is closed/deleted before it's truely done with it.

---

I've noticed that you commented the contents of the attachment and not the "<urn1:attach>...</urn1:attach>" itself. This is probably a source of errors.
Anyway, my suggestion would be to:
    - Create the document you want to create manually on Content Server.
    - Execute GetNode to retrieve that document.
    - Recreate the CreateDocument request by copying the relevant parts from the GetNode response and omitting the attachment.
        - You just need to change the name to avoid a conflict.
        - You have to be careful with the namespaces.
    - Add the attachment and try again.
By doing this you will limit the problem. For example:
    - By doing 1 and 2 you ensure you're not encoding things wrongly since the API gives you the exact values you need to use when creating a new document.
    - By doing 3 you test the simplest case first.
    - If you reach 4, then you know the problem is exclusively related with the content and you can focus there.
