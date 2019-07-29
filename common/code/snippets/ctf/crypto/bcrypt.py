import bcrypt, string, itertools

chars = string.lowercase + string.digits
partialPass = 'kztu6fe1m68mwf7vl1g3grjzmocia043pmno83q3ati98c8r324dzc0hc7n41p6tdjg6p'
bcryptHash = '$2y$10$FalJ8SmqTDBv7Fr366RC9uW5hKJVZijsDqzgASh1kSGMsUFMMLGZq'

def TestSuffix(permutationLen):
    charsPerm = [''.join(x) for x in itertools.permutations(chars, permutationLen)][::-1]
    
    total = len(charsPerm)
    for i in range(0, total):
        print '\r%d/%d' % (i, total - 1),
        
        password = partialPass + charsPerm[i]
        if (bcrypt.checkpw(password, bcryptHash)):
            print '\nPassword found: %s' % password
            return

TestSuffix(3)
