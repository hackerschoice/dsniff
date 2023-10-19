dsniff

The source was imported and patched like so and thereafter moved to `main` branch:
```
curl -fL http://deb.debian.org/debian/pool/main/d/dsniff/dsniff_2.4b1+debian.orig.tar.gz | tar xfz -
cd dsniff-2.4
curl -fL http://deb.debian.org/debian/pool/main/d/dsniff/dsniff_2.4b1+debian-31.debian.tar.xz | tar xf -
for x in {1..39}; do patch -p1 <debian/patches/$(printf "%02d" $x)_*; done
```
