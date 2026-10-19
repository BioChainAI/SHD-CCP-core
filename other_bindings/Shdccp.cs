// Optional hosted C# codec; requires standard .NET runtime, not for bare metal.
using System;
namespace FractalOS {
    public readonly record struct Fields(uint Core, byte Scale, byte StreamSlot,
        byte FormId, byte StepIndex, byte Gate, byte Structure, byte WheelUnit, byte CycleStep);
    public static class Shdccp {
        public static byte[] Encode(Fields f) {
            if (f.Scale>15 || f.StreamSlot>15 || f.FormId>15 || f.StepIndex>15 ||
                f.Structure>3 || f.WheelUnit>7 || f.CycleStep>7) throw new ArgumentOutOfRangeException();
            ulong w=f.Core | ((ulong)f.Scale<<32) | ((ulong)f.StreamSlot<<36) |
                ((ulong)f.FormId<<40) | ((ulong)f.StepIndex<<44) | ((ulong)f.Gate<<48) |
                ((ulong)f.Structure<<56) | ((ulong)f.WheelUnit<<58) | ((ulong)f.CycleStep<<61);
            var result=new byte[8];
            for (int i=7;i>=0;i--) {result[i]=(byte)w;w>>=8;}
            return result;
        }
    }
}
