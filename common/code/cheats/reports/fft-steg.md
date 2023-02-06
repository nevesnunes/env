# fft-steg

This is just a silly experiment with [Fourier transforms using GIMP](http://www.zoyinc.com/?p=1529). Although the linked plugin is quite old, compiling it from source works fine with GIMP 2.10.

So the idea is to take this test image:

<p align="center"><img src="./fft-steg/baboon.png" width=400rem></p>

Apply `Filters > Generic > FFT Forward`:

<p align="center"><img src="./fft-steg/baboon-fft-fwd.png" width=400rem></p>

Then type a message, minimizing possible artifacts by using a neutral grey foreground color (close to `#808080`), and a bitmap font (no other colours added from anti-aliasing):

<p align="center"><img src="./fft-steg/baboon-fft-fwd-msg.png" width=400rem></p>

After reverting with `Filters > Generic > FFT Inverse`:

<p align="center"><img src="./fft-steg/baboon-fft-inv-msg.png" width=400rem></p>

At first glance, not that bad for a 512x512 image! However, if we compare with the original image, there's noticable lines near the bottom. Here, let me make it clearer with a `composite baboon.png baboon-fft-inv-msg.png -compose difference baboon.diff.png`:

<p align="center"><img src="./fft-steg/baboon.diff.png" width=400rem></p>

Actually, it's even worse, most of the image was affected if we check with `compare baboon.png baboon-fft-inv-msg.png -metric RMSE baboon.rmse.png`:

<p align="center"><img src="./fft-steg/baboon.rmse.png" width=400rem></p>

That's pretty much it. You can toy around with placement to minimize artifacts, but in the end, this steganography is easily defeated once you know the "trick".
