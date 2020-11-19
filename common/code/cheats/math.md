# recursive formula from arithmetic sequence

- isolate factors
    - lowest common denominator => multiplying factor
    - diff between terms => additive factor
    - after k terms, a sequence starts repeating

- [CTFtime\.org / Balsn CTF 2020 / babyrev / Writeup](https://ctftime.org/writeup/24951)
    - https://github.com/10secTW/ctf-writeup/blob/master/2020/BalsnCTF/babyrev/babyrev_en.md
    ```scala
    // - fooList.flatMap(barList) will return elements of barList at indexes defined as values of fooList
    // - order of computation: map then flat
    def anon(a:Stream[Int], What:Seq[Seq[Int]]): Stream[Int] = { println(a toList, a.flatMap(What) toList); return a.sum #:: anon(a.flatMap(What), What) }
    (1 to 10).map{e => println(e); anon(Stream({0}), Seq(Seq(0,1,2,3), Seq(0), Seq(0), Seq(0)))(e)}
    /*
    What: (List(List(0, 1, 2, 3), List(0), List(0), List(0))

    (List(0),List(0, 1, 2, 3))
    (List(0, 1, 2, 3),List(0, 1, 2, 3, 0, 0, 0))
    (List(0, 1, 2, 3, 0, 0, 0),List(0, 1, 2, 3, 0, 0, 0, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3))
    (List(0, 1, 2, 3, 0, 0, 0, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3),List(0, 1, 2, 3, 0, 0, 0, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0))
    [...]
    scala.collection.immutable.IndexedSeq[Int] = Vector(6, 6, 24, 42, 114, 240, 582, 1302, 3048, 6954)

    scala> List(0).flatMap(Seq(Seq(0,1,2,3),Seq(0),Seq(0),Seq(0)))
    res103: List[Int] = List(0, 1, 2, 3)

    scala> List(0,1,2,3).flatMap(Seq(Seq(0,1,2,3),Seq(0),Seq(0),Seq(0)))
    res104: List[Int] = List(0, 1, 2, 3, 0, 0, 0)

    scala> List(0,1,2,3,0,0,0).flatMap(Seq(Seq(0,1,2,3),Seq(0),Seq(0),Seq(0)))
    res105: List[Int] = List(0, 1, 2, 3, 0, 0, 0, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3)
    */

    // fibonacci
    (1 to 10).map{e => println(e); anon(Stream({0}), Seq(Seq(0,1), Seq(0), Seq(0), Seq(0)))(e)}
    // || https://stackoverflow.com/questions/9864497/generate-a-sequence-of-fibonacci-number-in-scala
    val fibs:Stream[Int] = 0 #:: 1 #:: (fibs zip fibs.tail).map{ t => t._1 + t._2 }
    // || [That Fibonacci function in detail… - Luigi P](http://www.luigip.com/?p=200)
    val fibs:Stream[Int] = 0 #:: fibs.scanLeft(1)(_ + _)
    ```


