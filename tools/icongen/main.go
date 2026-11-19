package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	const size = 1024
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	blue := color.RGBA{0x25, 0x63, 0xeb, 0xff}
	white := color.RGBA{0xff, 0xff, 0xff, 0xf2}
	green := color.RGBA{0x22, 0xc5, 0x5e, 0xff}

	// 背景：圆角方块
	radius := float64(size) * 0.22
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if !insideRounded(float64(x), float64(y), size, radius) {
				continue
			}
			img.Set(x, y, blue)
		}
	}
	// 白色弧线：一条从左上到右下的通路
	for i := 0; i < 2000; i++ {
		t := float64(i) / 2000
		x := 0.22 + 0.56*t
		y := 0.66 - 0.30*math.Sin(math.Pi*t*0.85)
		drawDisc(img, x*size, y*size, size*0.045, white)
	}
	// 绿色圆点
	drawDisc(img, size*0.72, size*0.29, size*0.075, green)

	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		panic(err)
	}
}

func insideRounded(x, y, size, r float64) bool {
	if x < r && y < r {
		return math.Hypot(r-x, r-y) <= r
	}
	if x > size-r && y < r {
		return math.Hypot(x-(size-r), r-y) <= r
	}
	if x < r && y > size-r {
		return math.Hypot(r-x, y-(size-r)) <= r
	}
	if x > size-r && y > size-r {
		return math.Hypot(x-(size-r), y-(size-r)) <= r
	}
	return true
}

func drawDisc(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	for y := int(cy - r - 1); y <= int(cy+r+1); y++ {
		for x := int(cx - r - 1); x <= int(cx+r+1); x++ {
			if x < 0 || y < 0 || x >= img.Bounds().Dx() || y >= img.Bounds().Dy() {
				continue
			}
			if math.Hypot(float64(x)-cx, float64(y)-cy) <= r {
				img.Set(x, y, c)
			}
		}
	}
}
