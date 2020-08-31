# seams

layer > transform > offset

# light balance

duplicate layer
gaussian blur
invert colours
layer tab > mode > overlay

# lighten

duplicate layer
gradient tool
layer tab > mode > addition

# posterize, alpha channel

https://orbitingweb.com/blog/optimizing-png-images/

# xor

```bash
compare i1.png i2.png -metric RMSE o.png
```

### visual regression testing

- python - selenium webdriver `save_screenshot()` + Pillow `ImageChops.difference()`
    - https://jounileino.com/2019/05/17/visual-regression-testing.html
    - https://stackoverflow.com/questions/41721734/take-screenshot-of-full-page-with-selenium-python-with-chromedriver

- {!} changes in one element displace others => compute diff in DOM tree, style only changed elements


### responsive layouts

- [GitHub \- redecheck/redecheck: Automatically Detecting Layout Failures in Responsive Web Pages](https://github.com/redecheck/redecheck)
    - ~/Downloads/ReDeCheck - An Automatic Layout Failure Checking Tool for Responsively Designed Web Pages.pdf
    - user-defined layout constraints checked against different viewports

# levels

http://www.imagemagick.org/discourse-server/viewtopic.php?t=27719

# reversing gaussian blur

With G'MIC plugin:

Details > Sharpening

- Richardson-Lucy Deconvolution
- Gold-Meinel Deconvolution
