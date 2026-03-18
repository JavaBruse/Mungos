package ja4go

import "strconv"

// BuildJA4TInput описывает данные из TCP SYN-пакета клиента,
// необходимые для вычисления JA4T.
type BuildJA4TInput struct {
	// Номер пакета (опционально, библиотеке не нужен, но может пригодиться вызывающему коду).
	PacketNum int

	// Нефильтрованный размер окна (tcp.window_size_value).
	WindowSize uint16

	// Опции TCP в порядке появления (tcp.option_kind).
	Options []uint8

	// MSS из tcp.options.mss_val, если был.
	MSS *uint16

	// Window scale из tcp.options.wscale.shift, если был.
	WindowScale *uint8
}

// BuildJA4T возвращает строку JA4T в формате:
//   <window size>_<opt1-opt2-...>_<mss>_<wscale>
//
// Пример:
//   64240_2-1-3-1-1-4_1460_8
func BuildJA4T(in BuildJA4TInput) string {
	// Окно
	win := strconv.Itoa(int(in.WindowSize))

	// Опции
	opts := ""
	for i, k := range in.Options {
		if i > 0 {
			opts += "-"
		}
		opts += strconv.Itoa(int(k))
	}

	// MSS
	mss := "0"
	if in.MSS != nil {
		mss = strconv.Itoa(int(*in.MSS))
	}

	// Window scale
	ws := "0"
	if in.WindowScale != nil {
		ws = strconv.Itoa(int(*in.WindowScale))
	}

	return win + "_" + opts + "_" + mss + "_" + ws
}

