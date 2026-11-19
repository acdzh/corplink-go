package main

import "github.com/egoist/mygo/ui"

// Radix Colors 色阶（MIT © WorkOS），与参考项目一致：
// 1–2 背景、3–5 控件、6–8 边框、9–10 实心强调、11–12 文字。
var (
	radixSageLight = [...]string{
		"#fbfdfc", "#f7f9f8", "#eef1f0", "#e6e9e8", "#dfe2e0", "#d7dad9",
		"#cbcfcd", "#b8bcba", "#868e8b", "#7c8481", "#5f6563", "#1a211e",
	}
	radixSageDark = [...]string{
		"#101211", "#171918", "#202221", "#272a29", "#2e3130", "#373b39",
		"#444947", "#5b625f", "#63706b", "#717d79", "#adb5b2", "#eceeed",
	}
	radixGreenLight = [...]string{
		"#fbfefc", "#f4fbf6", "#e6f6eb", "#d6f1df", "#c4e8d1", "#adddc0",
		"#8eceaa", "#5bb98b", "#30a46c", "#2b9a66", "#218358", "#193b2d",
	}
	radixGreenDark = [...]string{
		"#0e1512", "#121b17", "#132d21", "#113b29", "#174933", "#20573e",
		"#28684a", "#2f7c57", "#30a46c", "#33b074", "#3dd68c", "#b1f1cb",
	}
	radixRedLight = [...]string{
		"#fffcfc", "#fff7f7", "#feebec", "#ffdbdc", "#ffcdce", "#fdbdbe",
		"#f4a9aa", "#eb8e90", "#e5484d", "#dc3e42", "#ce2c31", "#641723",
	}
	radixRedDark = [...]string{
		"#191111", "#201314", "#3b1219", "#500f1c", "#611623", "#72232d",
		"#8c333a", "#b54548", "#e5484d", "#ec5d5e", "#ff9592", "#ffd1d9",
	}
)

func clampStep(s int) int {
	if s < 1 {
		return 0
	}
	if s > 12 {
		return 11
	}
	return s - 1
}

func sage(dark bool, step int) ui.Color {
	if dark {
		return ui.Hex(radixSageDark[clampStep(step)])
	}
	return ui.Hex(radixSageLight[clampStep(step)])
}

func green(dark bool, step int) ui.Color {
	if dark {
		return ui.Hex(radixGreenDark[clampStep(step)])
	}
	return ui.Hex(radixGreenLight[clampStep(step)])
}

func red(dark bool, step int) ui.Color {
	if dark {
		return ui.Hex(radixRedDark[clampStep(step)])
	}
	return ui.Hex(radixRedLight[clampStep(step)])
}

// 字号与间距，对齐参考项目的 token。
const (
	fsH1    float32 = 17
	fsH2    float32 = 13.5
	fsBody  float32 = 13
	fsSmall float32 = 12
	fsTiny  float32 = 11

	radiusCard float32 = 14
	radiusRow  float32 = 8

	sidebarWidth float32 = 200
	pagePadX     float32 = 24
	pagePadY     float32 = 20
	padCard      float32 = 16
	gapCard      float32 = 12
)

// palette 是配色。同一组语义名，深浅两套值。
type palette struct {
	Dark bool

	Bg        ui.Color
	Sidebar   ui.Color
	Card      ui.Color
	CardHover ui.Color
	Border    ui.Color
	Separator ui.Color

	Text    ui.Color
	Muted   ui.Color
	Faint   ui.Color
	Heading ui.Color

	Green  ui.Color
	Red    ui.Color
	Yellow ui.Color

	OkBg     ui.Color
	AlertBg  ui.Color
	AccentBg ui.Color
}

func makePalette(dark bool) palette {
	return palette{
		Dark: dark,

		Bg:        sage(dark, 1),
		Sidebar:   sage(dark, 2),
		Card:      sage(dark, 1),
		CardHover: sage(dark, 3),
		Border:    sage(dark, 6),
		Separator: sage(dark, 5),

		Text:    sage(dark, 12),
		Heading: sage(dark, 12),
		Muted:   sage(dark, 11),
		Faint:   sage(dark, 9),

		Green:  green(dark, 11),
		Red:    red(dark, 11),
		Yellow: green(dark, 11),

		OkBg:     green(dark, 3),
		AlertBg:  red(dark, 3),
		AccentBg: green(dark, 9).Alpha(0.12),
	}
}

func pal(c *ui.Context) palette {
	if c.Theme().Dark {
		return makePalette(true)
	}
	return makePalette(false)
}

// card 画一个卡片容器。
func card(c *ui.Context, p palette, fn func()) {
	ui.Column(c).FillWidth().Radius(radiusCard).Padding(padCard).Gap(gapCard).
		Background(p.Card).Border(1, p.Border).Children(fn)
}

// sectionTitle 是内容区的小标题。
func sectionTitle(c *ui.Context, p palette, title, hint string) {
	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(8).Children(func() {
		ui.Text(c, title).FontSize(fsH2).Bold().TextColor(p.Heading)
		if hint != "" {
			ui.Text(c, hint).FontSize(fsTiny).TextColor(p.Faint).Grow(1).SingleLine()
		} else {
			ui.Spacer(c)
		}
	})
}

// hairline 是一条细分隔线。
func hairline(c *ui.Context, p palette) {
	ui.Box(c).FillWidth().Height(1).Background(p.Separator)
}
