extern "C" bool foo = true;
extern "C" bool bar = true;

// extern "C" void exit();

auto func() -> int {
  if (foo)
    return 0;
  
  if (bar)
    return 1;
 
  // exit();
  return 2;
}
