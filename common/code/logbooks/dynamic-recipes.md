# dynamic-recipes

[ ] query recipes with a set of ingredients
    suggest existing recipes sorted by largest count of included ingredients
    suggest additional matching ingredients for building a recipe from scratch
[ ] take unsorted sets of ingredientes to generate similar recipes
    https://github.com/ekzhu/SetSimilaritySearch
    https://stats.stackexchange.com/questions/285367/most-well-known-set-similarity-measures
    https://stackoverflow.com/questions/53753614/cosine-similarity-between-keywords
    https://janav.wordpress.com/2013/10/27/tf-idf-and-cosine-similarity/

[ ] visual diff between stages
    e.g. when an ingredient is raw vs. cooked - color, texture, noise...

Parings, Ingredient Substitutions
    Alert on possible incompatibilities with other ingredients
    Add steps to prepare ingredient
        slicing, cooking...
    Sort by ratios

Compute dosage adjustments

Ordering steps in recipes execution
    efficient use of time
    reduce errors/omissions
        starting state - tools, ingredients,...
    ---
    vertical gantt chart for parallel tasks

Pair photos with terms

### related work

https://www.escoffieronline.com/top-apps-for-finding-recipes-for-ingredients-you-already-have/
    https://www.supercook.com/#/recipes
    https://www.bigoven.com/recipes/leftover

datasets
https://dominikschmidt.xyz/simplified-recipes-1M/
    ~/Downloads/simplified-recipes-1M.npz
    ```python
    import numpy as np

    with np.load('simplified-recipes-1M.npz') as data:
        recipes = data['recipes']
        ingredients = data['ingredients']
    ```
    https://www.kaggle.com/hugodarwood/epirecipes
    https://www.kaggle.com/kaggle/recipe-ingredients-dataset
    https://www.kaggle.com/datafiniti/food-ingredient-lists
    https://eightportions.com/datasets/Recipes/
http://pic2recipe.csail.mit.edu/
    http://pic2recipe.csail.mit.edu/tpami19.pdf
    https://github.com/torralba-lab/im2recipe
https://www.reddit.com/r/datasets/comments/an6n26/are_there_any_freetouse_or_opensource_recipe/
    https://github.com/dspray95/open-recipe

[Turn recipe websites into plain text | Hacker News](https://news.ycombinator.com/item?id=23648864)
[Ask HN: Best Recipe Search Engine? | Hacker News](https://news.ycombinator.com/item?id=24630023)
[Show HN: Over 2M cooking recipes ready for text generation \| Hacker News](https://news.ycombinator.com/item?id=25356156)
    [Show HN: Instantly search 2M recipes \| Hacker News](https://news.ycombinator.com/item?id=25365397)


