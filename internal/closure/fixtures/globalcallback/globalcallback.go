package globalcallback

type callback func() int

var current = callback(local)

func local() int { return 1 }

func alternate() int { return 2 }

func Set() { current = alternate }

func F() int { return current() }
