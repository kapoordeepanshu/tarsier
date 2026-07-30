package report

import "html/template"

// Device class glyphs.
//
// Drawn as a consistent set on a 16-unit grid with a single stroke weight, so a
// column of them reads as one family rather than a pile of clip art. They
// inherit currentColor, which lets the row's severity tint the icon without a
// second asset.
//
// They earn their place by making the inventory scannable: a person looking for
// "the cameras" finds them by shape far faster than by reading a class column.
const iconBase = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">`

var icons = map[string]string{
	// Sheet feeding out of a body.
	"printer": `<path d="M4 6V2h8v4"/><rect x="2" y="6" width="12" height="5" rx="1"/><path d="M4 11v3h8v-3"/><circle cx="12" cy="8" r=".6" fill="currentColor" stroke="none"/>`,
	// Body and lens on a bracket.
	"camera": `<path d="M2 5h8a2 2 0 0 1 2 2v3H2z"/><path d="M12 7l3-1.5v5L12 9"/><path d="M4 10v4"/><circle cx="6" cy="7.5" r="1.3"/>`,
	// Stacked units with status lights.
	"server": `<rect x="2" y="2.5" width="12" height="4.5" rx="1"/><rect x="2" y="9" width="12" height="4.5" rx="1"/><circle cx="4.5" cy="4.75" r=".6" fill="currentColor" stroke="none"/><circle cx="4.5" cy="11.25" r=".6" fill="currentColor" stroke="none"/>`,
	// Screen on a stand.
	"workstation": `<rect x="1.5" y="3" width="13" height="8" rx="1"/><path d="M6 14h4M8 11v3"/>`,
	// Handset with a keypad.
	"phone": `<rect x="3.5" y="1.5" width="9" height="13" rx="1.5"/><path d="M5.5 4.5h5M5.5 7h5M5.5 9.5h5"/>`,
	// Slab with a single button.
	"mobile": `<rect x="4.5" y="1.5" width="7" height="13" rx="1.5"/><path d="M7 12.8h2"/>`,
	// Drive bays.
	"nas": `<rect x="2.5" y="2" width="11" height="12" rx="1"/><path d="M5 5h6M5 8h6M5 11h6"/>`,
	// Controller with I/O terminals.
	"plc": `<rect x="2" y="4" width="12" height="8" rx="1"/><path d="M5 4V2M8 4V2M11 4V2M5 12v2M8 12v2M11 12v2"/><path d="M5.5 8h5"/>`,
	// Switch with ports and uplink.
	"network": `<rect x="1.5" y="6" width="13" height="5" rx="1"/><path d="M4 6V3.5M8 6V3.5M12 6V3.5"/><path d="M4 11v1.5M8 11v1.5M12 11v1.5"/>`,
	// A screen inside a screen.
	"vm": `<rect x="1.5" y="3" width="13" height="9" rx="1"/><rect x="4.5" y="5.5" width="7" height="4" rx=".5"/>`,
	// Sensor emitting.
	"iot": `<circle cx="8" cy="10.5" r="2"/><path d="M4.8 7.3a4.5 4.5 0 0 1 6.4 0"/><path d="M2.8 5.2a7.4 7.4 0 0 1 10.4 0"/>`,
	// Question left deliberately plain: an unknown device should look unknown.
	"unknown": `<circle cx="8" cy="8" r="6"/><path d="M6.3 6.2a1.8 1.8 0 0 1 3.4.8c0 1.2-1.7 1.4-1.7 2.4"/><circle cx="8" cy="11.6" r=".6" fill="currentColor" stroke="none"/>`,
}

func classIcon(class string) template.HTML {
	body, ok := icons[class]
	if !ok {
		body = icons["unknown"]
	}
	// Assembled from constants only — no caller input reaches the markup.
	return template.HTML(iconBase + body + `</svg>`)
}
